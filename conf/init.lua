--------------全局设置-----------------

s_url = ngx.shared.s_url; --用于记录单用户请求同一url的次数
a_url = ngx.shared.a_url; --用于记录单用户所有请求次数
d_url = ngx.shared.d_url; --用于记录动态页面的请求次数
bad_user = ngx.shared.bad_user; --黑名单词典
ban_time = 600; --黑名单时间,单位:秒.

--cookie标记开关,用来解决多用户共享ip上网误判的问题.
--攻击者也可能利用cookie跳过限制
--0为关闭,1为开启.
cookie_enable = 0;

-----------静态资源变量设置--------------

s_url_max = 10; --单个url 10秒内允许最大访问次数
a_url_max = 60; --10秒内允许的最大总访问次数

------------动态网页变量设置---------------

d_url_max = 10; --10秒内允许的最大总访问次数
jscc = 0;       --js防cc开关,0为关闭,1为开启. 
white_time = 600; -- js跳转验证后白名单的时间.
--ignore_spider = "baiduspider|googlebot"; --搜索引擎js防cc白名单,注释则不启用
sql_filter = 1; --sql防注入开关,0为关闭,1为开启.
sql_rule = ".*[; ]?((or)|(insert)|(select)|(union)|(update)|(delete)|(replace)|(create)|(drop)|(alter)|(grant)|(load)|(show)|(exec))[\\s(]" --sql防注入规则
filte_file_type = "php|jsp";--禁止上传的文件后缀,注释则不过滤
