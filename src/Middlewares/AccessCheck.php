<?php

namespace Lzpeng\Auth\Think\Middlewares;

use Lzpeng\Auth\Exception\AccessException;
use Lzpeng\Auth\Think\Auth;
use think\Request;

/**
 * 基于controller/action的权限访问检查
 * 
 * @author 刘展鹏 <liuzhanpeng@gmail.com>
 */
class AccessCheck
{
    public function handle(Request $request, \Closure $next, $name)
    {
        $controller = $request->controller(true);
        $action = $request->action(true);

        if (!Auth::create($name)->isAllowed($controller . '/' . $action)) {
            throw new AccessException('没有权限');
        }

        return $next($request);
    }
}
