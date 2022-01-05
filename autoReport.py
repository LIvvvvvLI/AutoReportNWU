# -*- coding: utf-8 -*-
import requests
import json
import datetime
from bs4 import BeautifulSoup
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import argparse

DEBUG = False


class CookiesTimeOutError(Exception):
    def __init__(self):
        Exception.__init__(self)

    def __str__(self):
        return 'cookies失效'


class PassWordError(Exception):
    def __int__(self):
        Exception.__init__(self)

    def __str__(self):
        return '密码错误'


class DataLackError(Exception):
    def __int__(self):
        Exception.__init__(self)

    def __str__(self):
        return '输入数据不足'


def get_aes_string(data, key, iv):
    """AES-128-CBC加密模式"""
    mode = AES.MODE_CBC
    cryptos = AES.new(key.encode(), mode, iv.encode())
    cipher_text = cryptos.encrypt(pad(data.encode('utf-8'), AES.block_size))
    result = base64.encodebytes(cipher_text).decode()
    result = result.replace('\n', '')
    return result


def encrypt(password, pwdDefaultEncryptSalt):
    """加密密码"""
    random_string_64 = '2345678ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678ABCDEFGHJ'
    return get_aes_string(random_string_64+password, pwdDefaultEncryptSalt, pwdDefaultEncryptSalt)


def save_log(text):
    """保存结果至同目录下log.txt"""
    # 以x月x日的名称保存填报结果
    with open(file='saveLog.txt', mode='a') as f:
        f.write(str(datetime.datetime.now()).split('.')[0] + '  :  ' + text + '\n')


def save_cookies(cookies):
    """保存cookies到本地cookies.json"""
    with open(file='cookies.json', mode='w') as f:
       json.dump(cookies, f)


def read_cookies():
    """从本地cookies.json读取cookies"""
    with open(file='cookies.json', mode='r') as f:
        return json.load(f)

def save_data_report(data_report):
    """写入report_data，更建议直接改reportdata.json"""
    with open(file='reportdata.json', mode='w') as f:
        json.dump(data_report, f)


def read_data_report():
    with open(file='reportdata.json', mode='r') as f:
        return json.load(f)


def login_sys(username, password):
    """登录系统"""
    url_sys = 'http://authserver.nwu.edu.cn'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.428'
                      '0.88 Safari/537.36 Edg/87.0.664.60',
    }
    res = requests.get(url=url_sys, headers=headers)  # 请求登录界面
    # {'JSESSIONID': ''}
    cookies_JSESSIONID = requests.utils.dict_from_cookiejar(res.cookies)
    if DEBUG:
        print("1. " + str(cookies_JSESSIONID))

    bs = BeautifulSoup(res.content, "html.parser")
    dist0 = bs.find_all('input', {'type': "hidden"})  # 寻找登录界面中需要的数据
    dist = {}
    for i in dist0:
        try:
            dist[re.search('(?<=name=").*?(?=")', str(i)).group()] = re.search('(?<=value=").*?(?=")', str(i)).group()
        except:
            dist[re.search('(?<=id=").*?(?=")', str(i)).group()] = re.search('(?<=value=").*?(?=")', str(i)).group()

    temp = str(bs.find_all(type="text/javascript")[0])
    pwdDefaultEncryptSalt = temp.split('"')[5]
    enPassword = encrypt(password, pwdDefaultEncryptSalt)
    dist['dllt'] = 'userNamePasswordLogin'
    params_login = {
        'username': '%s' % username,
        'password': '%s' % enPassword,
        'lt': '%s' % dist['lt'],
        'dllt': '%s' % dist['dllt'],
        'execution': '%s' % dist['execution'],
        '_eventId': '%s' % dist['_eventId'],
        'rmShown': '%s' % dist['rmShown'],
    }

    # 请求登录页面
    url_login_sys = 'http://authserver.nwu.edu.cn/authserver/login'
    html = requests.post(url=url_login_sys,
                         headers=headers,
                         params=params_login,
                         cookies=cookies_JSESSIONID,
                         allow_redirects=False
                         )
    # 密码错误的判断，或许不充分
    if html.status_code == 302:
        pass
        # print('登入成功')
    else:
        raise PassWordError()
        # print('登入失败')
    # {'iPlanetDirectoryPro': '', 'CASTGC': ''}
    cookies_login = requests.utils.dict_from_cookiejar(html.cookies)
    if DEBUG:
        print("2. " + str(cookies_login))
    return cookies_login


def login_app(headers, cookies):
    """登录 app端"""
    params_ncov = {
        'redirect': 'https://app.nwu.edu.cn/site/ncov/dailyup'
    }

    # 这里如果 allow_redirects==True，则无法获得 cookies_eai;
    # 而 allow_redirects==False，则重定位未执行，app登录过程不完整，cookies_eai在 report时不被认可。
    url_login_app = 'https://app.nwu.edu.cn/uc/wap/login'
    resq = requests.get(url=url_login_app,
                        headers=headers,
                        cookies=cookies,
                        params=params_ncov,
                        allow_redirects=False
                        )  # 请求登录界面
    # {'UUkey': '', 'eai-sess': ''}
    cookies_eai = requests.utils.dict_from_cookiejar(resq.cookies)
    if DEBUG:
        print("3. " + str(cookies_eai))
    # {'UUkey': '', 'eai-sess': '', 'iPlanetDirectoryPro': '', 'CASTGC': ''}
    cookies_final = {}
    cookies_final['UUkey'] = cookies_eai['UUkey']
    cookies_final['eai-sess'] = cookies_eai['eai-sess']
    cookies_final['iPlanetDirectoryPro'] = cookies['iPlanetDirectoryPro']
    cookies_final['CASTGC'] = cookies['CASTGC']
    if DEBUG:
        print('Final: ' + str(cookies_final))

    params_abc = {
        'redirect': '/site/center/personal',
        'from': 'wap',
    }
    url_app_check = 'https://app.nwu.edu.cn/a_nwu/api/sso/cas'
    abc = requests.get(url=url_app_check,
                       headers=headers,
                       cookies=cookies_final,
                       params=params_abc,
                       allow_redirects=True
                       )
    if DEBUG:
        cookies_abc = requests.utils.dict_from_cookiejar(abc.cookies)
        print("4. " + str(cookies_abc))
    cookies_eai['iPlanetDirectoryPro'] = cookies['iPlanetDirectoryPro']
    return cookies_eai


def login(username, password):
    """登录"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.428'
                      '0.88 Safari/537.36 Edg/87.0.664.60',
    }
    cookies_login = login_app(headers, login_sys(username, password))
    return cookies_login


def report(headers, data, cookies):
    """填报，返回填报结果"""
    url_report = 'https://app.nwu.edu.cn/ncov/wap/open-report/save'
    save = requests.post(url=url_report, headers=headers, data=data, cookies=cookies)
    message = save.text.split('"')[5]
    if message == '用户信息已失效,请重新进入页面':
        raise CookiesTimeOutError()
    else:
        return message


if __name__ == '__main__':
    headers_report = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest"
    }
    """
    data_report = {
        'sfzx': '',  # 是否在校
        'tw': '',  # 体温
        'area': '',  # 地区
        'city': '',  # 市
        'province': '',  # 省
        'address': '',  # 地址
        'geo_api_info': '',  # 定位
        'sfcyglq': '0',  # 是否处于隔离期
        'sfyzz': '0',  # 是否有症状
        'qtqk': '',  # 其他情况
        'ymtys': ''  # 一码通颜色
    }
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('mode', default='local', type=str, choices=['local', 'online'], help='where you want run')
    parser.add_argument('--username', type=str, help='your username')
    parser.add_argument('--password', type=str, help='your password')
    args = parser.parse_args()

    data_report = read_data_report()
    cookies = ''

    try:
        # 本地模式
        if args.mode == 'local':
            if (args.username is not None) and (args.password is not None):
                cookies = login(args.username, args.password)
                save_cookies(cookies)
            else:
                cookies = read_cookies()
        # 在线模式
        else:
            if (args.username is not None) and (args.password is not None):
                cookies = login(args.username, args.password)
            else:
                raise DataLackError
    except FileNotFoundError:
        print('本地无用户信息，请通过命令行参数传入账号密码重试。')
    except DataLackError:
        print('请通过命令行参数传入账号密码重试。')
    except CookiesTimeOutError:
        print('cookies过期，请通过命令行参数传入账号密码重试。')
    else:
        result = report(headers=headers_report, data=data_report, cookies=cookies)
        print(result)
