<?php

namespace Lzpeng\Auth\Think;

/**
 * 密码提供接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface PasswordInterface
{
    /**
     * 返回用户份对象中的密码信息
     *
     * @return string
     */
    public function password();
}
