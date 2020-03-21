<?php

namespace Lzpeng\Auth\Think\Middlewares;

use Lzpeng\Auth\Think\Auth;
use Lzpeng\Auth\Exception\AuthException;
use think\Request;

/**
 * 认证检查中间件
 * 可通过传入额外参数给中间件使用不同的认证器做检查
 * 
 * @author 刘展鹏 <liuzhanpeng@gmail.com>
 */
class AuthCheck
{
    public function handle(Request $request, \Closure $next, $name)
    {
        if (!Auth::create($name)->isLogined()) {
            throw new AuthException('认证失败');
        }

        return $next($request);
    }
}
