http-guard简介

    这个是基于openresty开发出来的web防火墙，主要功能有
    *   静态页面防cc攻击
    *   动态页面防cc攻击(包括js跳转认证)
    *   防止sql注入攻击
    *   防止上传php webshell
    *   防止xss攻击
    *   取消特定目录php执行权限
    
安装方法
    
    代码下载回来后，执行install.sh脚本开始安装。
    
使用方法

    复制conf目录下的lua文件到/usr/local/nginx/conf下,在nginx.conf配置文件中的http代码段加入如下代码：
        lua_shared_dict s_url 10m;
        lua_shared_dict a_url 10m;
        lua_shared_dict d_url 10m;
        lua_shared_dict bad_user 10m;
        lua_shared_dict js_verify 10m;    
        init_by_lua_file 'conf/init.lua';
        header_filter_by_lua_file 'conf/send_cookie.lua';
        access_by_lua_file 'conf/http_guard.lua';
		
	一些初始参数可以在init.lua文件修改	