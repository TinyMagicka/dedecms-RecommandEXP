#encoding:gbk

#exp tool for dedecms recommand.php sql injection.  
#searching using google automatically then trying to explore it withing EXP

"""
本程序是织梦 dedecms recommand.php 的注入漏洞自动化利用工具。
1）使用google镜像来搜索漏洞网站因此镜像可能过段时间就不管用了，那时候只要稍作修改“使用google镜像抓取的配置信息”就行了。
2）程序有些边界设置没有考虑，比如google搜索页数没有上限；子线程不停的进行select没有考虑到数据库记录为空的情况等；
3）由于python的GIL锁所以python不支持真的多线程，不过本程序并不是计算密集型程序，所以这也没关系，不过最好还是多进程+协程。
"""

