<?php

namespace Lzpeng\Auth\Think;

use Lzpeng\Auth\AbstractAuth;
use Lzpeng\Auth\Exception\ConfigException;
use Lzpeng\Auth\Think\Authenticators\SessionAuthenticator;
use Lzpeng\Auth\Think\Hashers\HasherInterface;
use Lzpeng\Auth\Think\UserProviders\ModelUserProvider;
use think\Container;

class Auth extends AbstractAuth
{
    /**
     * @inheritDoc
     */
    protected function init($authManager)
    {
        $authManager->registerUserProviderCreator('model', function ($config) {
            $modelClass = $config['model'];
            $idKey = $config['id_key'] ?? 'id';
            $passwordKey = $config['password_key'] ?? 'password';

            // 因为hasher一般在其它场景(创建用户、修改密码等)时也会用到，所以直接获取注入容器内的hasher组件
            $hasher = Container::get(HasherInterface::class);
            if (is_null($hasher)) {
                throw new ConfigException('注入容器中找不到实现HashInterfacer接口的hasher组件');
            }

            return new ModelUserProvider($modelClass, $idKey, $passwordKey, $hasher);
        });

        $authManager->registerAuthenticatorCreator('session', function ($config) {
            if (isset($config['session_key'])) {
                throw new ConfigException('SessionAuthenticator需要配置session_key');
            }
            return new SessionAuthenticator($config['session_key'], Container->get('session'));
        });
    }

    /**
     * @inheritDoc
     */
    protected function getConfig()
    {
        return config('auth.');
    }
}
