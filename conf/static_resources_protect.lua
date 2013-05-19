local ip = ngx.var.binary_remote_addr;
local cookie = ngx.var.cookie_httpguard;

if not cookie then
	cookie = 100000000;
end

if cookie_enable==1 then
	--计算ip与cookie的md5
	local aurl_flag = ngx.md5(table.concat({ip,cookie}));
	local baduser,_=bad_user:get(aurl_flag)
	--判断此用户是否在黑名单
	if baduser then
		ngx.exit(444);
	else
		local uri = ngx.var.request_uri;
		--计算ip与cookie,uri的md5,用于限制单个url请求速度
		local surl_flag = ngx.md5(table.concat({ip,cookie,uri}));
		local surl = s_url:get(surl_flag);
		local aurl = a_url:get(aurl_flag);
		--判断s_url字典是否存在
		if surl then
			--判断此用户访问单个url是否超过限制
			if surl > s_url_max then
				--加入黑名单
				bad_user:set(aurl_flag,0,ban_time);
				--断开连接
				ngx.exit(444);
			else
				--该用户访问此url次数加1
				s_url:incr(surl_flag,1);
			end
		else
			--添加记录进s_url词典
			s_url:set(surl_flag,1,10);
		end
		--判断a_url字典是否存在
		if aurl then
			--判断此用户总访问数是否超过限制
			if aurl > a_url_max then
				--加入黑名单
				bad_user:set(aurl_flag,0,ban_time);
				--断开连接
				ngx.exit(444);
			else
				--该用户访问此url次数加1
				a_url:incr(aurl_flag,1);
			end	
		else
			--添加记录进a_url词典
			a_url:set(aurl_flag,1,10);
		end
	end
else
	local aurl_flag = ip;
	local baduser,_=bad_user:get(aurl_flag)
	--判断此用户是否在黑名单
	if baduser then
		ngx.exit(444);
	else
		local uri = ngx.var.request_uri;
		--计算ip与cookie,uri的md5,用于限制单个url请求速度
		local surl_flag = ngx.md5(table.concat({ip,uri}));
		local surl = s_url:get(surl_flag);
		local aurl = a_url:get(aurl_flag);
		--判断s_url字典是否存在
		if surl then
			--判断此用户访问单个url是否超过限制
			if surl > s_url_max then
				--加入黑名单
				bad_user:set(aurl_flag,0,ban_time);
				--断开连接
				ngx.exit(444);
			else
				--该用户访问此url次数加1
				s_url:incr(surl_flag,1);
			end
		else
			--添加记录进s_url词典
			s_url:set(surl_flag,1,10);
		end
		--判断a_url字典是否存在
		if aurl then
			--判断此用户总访问数是否超过限制
			if aurl > a_url_max then
				--加入黑名单
				bad_user:set(aurl_flag,0,ban_time);
				--断开连接
				ngx.exit(444);
			else
				--该用户访问此url次数加1
				a_url:incr(aurl_flag,1);
			end	
		else
			--添加记录进a_url词典
			a_url:set(aurl_flag,1,10);
		end
	end
end	
