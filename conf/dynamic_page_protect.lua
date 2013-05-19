local ip = ngx.var.binary_remote_addr;
local cookie = ngx.var.cookie_httpguard;

if not cookie then
	cookie = 100000000;
end

--请求限速
if cookie_enable==1 then
	--计算ip与cookie的md5
	local durl_flag = ngx.md5(table.concat({ip,cookie}));
	local baduser,_=bad_user:get(durl_flag);
	--判断此用户是否在黑名单
	if baduser then
		ngx.exit(444);
	else
		local durl = d_url:get(durl_flag);
		--判断a_url字典是否存在
		if durl then
			--判断此用户总访问数是否超过限制
			if durl > d_url_max then
				--加入黑名单
				bad_user:set(durl_flag,0,ban_time);
				--断开连接
				ngx.exit(444);
			else
				--该用户访问此url次数加1
				d_url:incr(durl_flag,1);
			end	
		else
			--添加记录进a_url词典
			d_url:set(durl_flag,1,10);
		end
	end
else
	local durl_flag = ip;
	local baduser,_=bad_user:get(durl_flag);
	--判断此用户是否在黑名单
	if baduser then
		ngx.exit(444);
	else
		local durl = d_url:get(durl_flag);
		--判断a_url字典是否存在
		if durl then
			--判断此用户总访问数是否超过限制
			if durl > d_url_max then
				--加入黑名单
				bad_user:set(durl_flag,0,ban_time);
				--断开连接
				ngx.exit(444);
			else
				--该用户访问此url次数加1
				d_url:incr(durl_flag,1);
			end	
		else
			--添加记录进a_url词典
			d_url:set(durl_flag,1,10);
		end
	end
end	

--请求过滤
if (ngx.req.get_method()=="GET") then
	local uri = ngx.var.request_uri;
	--开启js防cc攻击
	if jscc==1 then
		local jsjump = ngx.shared.jsjump;
		local jspara,flags = jsjump:get(ip);
		local args = ngx.req.get_uri_args();
		if jspara then
			if flags then
				ngx.exec("@php");
			else
				local p_jskey=''
				if args["jskey"] and type(args["jskey"])=='table' then
						p_jskey=args["jskey"][table.getn(args["jskey"])];
				else
						p_jskey=args["jskey"];
				end
				if p_jskey and p_jskey==tostring(jspara) then
					jsjump:set(ip,jspara,white_time,1);
					ngx.exec("@php");
				else
					local url=''
					if ngx.var.args then
						url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"&jskey=",jspara});
					else
						url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"?jskey=",jspara});
					end
					local jscode=table.concat({"<script>window.location.href='",url,"';</script>"});
					ngx.say(jscode)
				end
			end
		else
			math.randomseed( os.time() );
			local random=math.random(100000,999999)
			jsjump:set(ip,random,60)
			local url=''
			if ngx.var.args then
				url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"&jskey=",random});
			else
				url=table.concat({ngx.var.scheme,"://",ngx.var.host,uri,"?jskey=",random});
			end
			local jscode=table.concat({"<script>window.location.href='",url,"';</script>"});
			ngx.say(jscode)
		end
	elseif sql_filter==1 then
		url=ngx.unescape_uri(uri);
		local m,err = ngx.re.match(url,sql_rule,"i")
		if m then
			ngx.exit(444);
		end
		ngx.exec("@php");
	end
elseif (ngx.req.get_method()=="POST") then
	ngx.exec("@php");
else
	ngx.exec("@php");
end