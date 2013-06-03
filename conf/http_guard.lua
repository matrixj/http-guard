if not cookie then
	cookie = 100000000;
end

local ip = ngx.var.binary_remote_addr;
local cookie = ngx.var.cookie_httpguard;
local uri = ngx.var.request_uri;
local filename = ngx.var.request_filename;
local ip_cookie = ngx.md5(table.concat({ip,cookie}));

--请求限速
if cookie_enable==1 then
	--计算ip与cookie的md5
	local baduser,_=bad_user:get(ip_cookie)
	--判断此用户是否在黑名单
	if baduser then
		ngx.exit(444);
	else
		--当url请求的是php文件时
		if ngx.re.match(filename,".*\\.php$","i") then
			local durl = d_url:get(ip_cookie);
			--判断a_url字典是否存在
			if durl then
				--判断此用户总访问数是否超过限制
				if durl > d_url_max then
					--加入黑名单
					bad_user:set(ip_cookie,0,ban_time);
					--断开连接
					ngx.exit(444);
				else
					--该用户访问此url次数加1
					d_url:incr(ip_cookie,1);
				end	
			else
				--添加记录进a_url词典
				d_url:set(ip_cookie,1,10);
			end	
		else
			--计算ip与cookie,uri的md5,用于限制单个url请求速度
			local ip_cookie_uri = ngx.md5(table.concat({ip,cookie,uri}));
			local surl = s_url:get(ip_cookie_uri);
			local aurl = a_url:get(ip_cookie);
			--判断s_url字典是否存在
			if surl then
				--判断此用户访问单个url是否超过限制
				if surl > s_url_max then
					--加入黑名单
					bad_user:set(ip_cookie,0,ban_time);
					--断开连接
					ngx.exit(444);
				else
					--该用户访问此url次数加1
					s_url:incr(ip_cookie_uri,1);
				end
			else
				--添加记录进s_url词典
				s_url:set(ip_cookie_uri,1,10);
			end
			--判断a_url字典是否存在
			if aurl then
				--判断此用户总访问数是否超过限制
				if aurl > a_url_max then
					--加入黑名单
					bad_user:set(ip_cookie,0,ban_time);
					--断开连接
					ngx.exit(444);
				else
					--该用户访问此url次数加1
					a_url:incr(ip_cookie,1);
				end	
			else
				--添加记录进a_url词典
				a_url:set(ip_cookie,1,10);
			end
		end	
	end
else
	local baduser,_=bad_user:get(ip)
	--判断此用户是否在黑名单
	if baduser then
		ngx.exit(444);
	else
		--当请求的是php文件时
		if ngx.re.match(filename,".*\\.php$","i") then
			local durl = d_url:get(ip);
			--判断a_url字典是否存在
			if durl then
				--判断此用户总访问数是否超过限制
				if durl > d_url_max then
					--加入黑名单
					bad_user:set(ip,0,ban_time);
					--断开连接
					ngx.exit(444);
				else
					--该用户访问此url次数加1
					d_url:incr(ip,1);
				end	
			else
				--添加记录进a_url词典
				d_url:set(ip,1,10);
			end	
		else
			--计算ip与cookie,uri的md5,用于限制单个url请求速度
			local ip_uri = ngx.md5(table.concat({ip,uri}));
			local surl = s_url:get(ip_uri);
			local aurl = a_url:get(ip);
			--判断s_url字典是否存在
			if surl then
				--判断此用户访问单个url是否超过限制
				if surl > s_url_max then
					--加入黑名单
					bad_user:set(ip,0,ban_time);
					--断开连接
					ngx.exit(444);
				else
					--该用户访问此url次数加1
					s_url:incr(ip_uri,1);
				end
			else
				--添加记录进s_url词典
				s_url:set(ip_uri,1,10);
			end
			--判断a_url字典是否存在
			if aurl then
				--判断此用户总访问数是否超过限制
				if aurl > a_url_max then
					--加入黑名单
					bad_user:set(ip_cookie,0,ban_time);
					--断开连接
					ngx.exit(444);
				else
					--该用户访问此url次数加1
					a_url:incr(ip_cookie,1);
				end	
			else
				--添加记录进a_url词典
				a_url:set(ip_cookie,1,10);
			end
		end	
	end
end

--请求过滤
if (ngx.req.get_method()=="GET") then
	--js跳转验证
	if jscc==1 then
		local js_verify = ngx.shared.js_verify;
		local jspara,flags = js_verify:get(ip);
		local args = ngx.req.get_uri_args();
		if jspara then
			if not flags then
				local p_jskey=''
				if args["jskey"] and type(args["jskey"])=='table' then
						p_jskey=args["jskey"][table.getn(args["jskey"])];
				else
						p_jskey=args["jskey"];
				end
				if p_jskey and p_jskey==tostring(jspara) then
					js_verify:set(ip,jspara,white_time,1);
				else
					local url=''
					if ngx.var.args then
						url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"&jskey=",jspara});
					else
						url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"?jskey=",jspara});
					end
					local jscode=table.concat({"<script>window.location.href='",url,"';</script>"});
					ngx.header.content_type = "text/html"
					ngx.print(jscode)
					ngx.exit(200)
				end
			end
		else
			math.randomseed( os.time() );
			local random=math.random(100000,999999)
			js_verify:set(ip,random,60)
			local url=''
			if ngx.var.args then
				url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"&jskey=",random});
			else
				url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"?jskey=",random});
			end
			local jscode=table.concat({"<script>window.location.href='",url,"';</script>"});
			ngx.header.content_type = "text/html"
			ngx.print(jscode)
			ngx.exit(200)
		end
	end

	--是否开启防sql注入	
	if sql_filter then
		url=ngx.unescape_uri(uri);
		if ngx.re.match(url,sql_filter,"i") then
			ngx.exit(444);
		end
	end	
	--是否开启防xss攻击
	if filte_xss then
		url=ngx.unescape_uri(uri)
		if ngx.re.match(url,filte_xss,"i") then
			ngx.exit(444)
		end	
	end
elseif (ngx.req.get_method()=="POST") then
	--是否开启防止php等文件上传
	if filte_file_type then
		ngx.req.read_body()
		if ngx.req.get_body_data() and ngx.re.match(ngx.req.get_body_data(),"Content-Disposition: form-data;.*filename=\"(.*)."..filte_file_type.."\"","isjo") then
			return 444
		end
	end	
end