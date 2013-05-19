--初始化三个词典
s_url = ngx.shared.s_url;
a_url = ngx.shared.a_url;
bad_user = ngx.shared.bad_user;


--黑名单时间,单位:秒.
ban_time = 600;

--cookie标记开关,用来解决多用户共享ip上网误判的问题.
--攻击者也可能利用cookie跳过限制
--0为关闭,1为开启.
cookie_enable = 0;

-----------静态资源变量设置--------------

--单个url 10秒内允许最大访问次数
s_url_max = 10;

--10秒内允许的最大总访问次数
a_url_max = 60;

------------动态网页变量设置---------------

--10秒内允许的最大总访问次数
d_url_max = 10;

--js防cc开关,0为关闭,1为开启.
jscc = 0;

--搜索引擎js防cc白名单
spider_list="baiduspider|googlebot";

--针对搜索引擎不启用js防cc开关,0为关闭,1为开启.
spider_jscc = 0;

--sql防注入开关,0为关闭,1为开启.
sql_filter = 1;

--防止上传特定文件,如php文件,0为关闭,1为开启.
upload_filter = 1;

--禁止上传的文件后缀.
file_type = "php|jsp";
