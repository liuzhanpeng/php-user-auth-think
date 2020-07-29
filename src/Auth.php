<?php

namespace Lzpeng\Auth\Think;

use Lzpeng\Auth\AbstractAuth;
use Lzpeng\Auth\Exception\ConfigException;
use Lzpeng\Auth\Think\Authenticators\OnceAuthenticator;
use Lzpeng\Auth\Think\Authenticators\SessionAuthenticator;
use Lzpeng\Auth\Think\Authenticators\TokenAuthenticator;
use Lzpeng\Auth\Think\Hashers\BcryptHasher;
use Lzpeng\Auth\Think\Hashers\HasherInterface;
use Lzpeng\Auth\Think\UserProviders\ModelUserProvider;
use Lzpeng\Auth\UserProviders\DbUserProvider;
use think\Container;

class Auth extends AbstractAuth
{
    /**
     * @inheritDoc
     */
    static protected function init($authManager)
    {
        parent::init($authManager);

        $authManager->registerUserProviderCreator('model', function ($config) {
            if (!isset($config['model'])) {
                throw new ConfigException('ModelUserProvider需要配置model');
            }

            $modelClass = $config['model'];
            $idKey = $config['id_key'] ?? 'id';
            $passwordKey = $config['password_key'] ?? 'password';
            $hasherConfig = $config['hasher'] ?? ['driver' => BcryptHasher::class];

            Container::set(HasherInterface::class, $hasherConfig['driver']);
            $hasher = Container::get(HasherInterface::class, $hasherConfig['params'] ?? []);

            return new ModelUserProvider($modelClass, $idKey, $passwordKey, $hasher);
        });

        $authManager->registerUserProviderCreator('db', function ($config) {
            if (!isset($config['table'])) {
                throw new ConfigException('DbUserProvider需要配置table');
            }

            $table = $config['table'];
            $idKey = $config['id_key'] ?? 'id';
            $passwordKey = $config['password_key'] ?? 'password';
            $hasherConfig = $config['hasher'] ?? ['driver' => BcryptHasher::class];

            Container::set(HasherInterface::class, $hasherConfig['driver']);
            $hasher = Container::get(HasherInterface::class, $hasherConfig['params'] ?? []);

            return new DbUserProvider($table, $idKey, $passwordKey, $hasher);
        });

        $authManager->registerAuthenticatorCreator('session', function ($config) {
            if (!isset($config['session_key'])) {
                throw new ConfigException('SessionAuthenticator需要配置session_key');
            }

            return new SessionAuthenticator($config['session_key'], Container::get('session'));
        });

        $authManager->registerAuthenticatorCreator('token', function ($config) {
            if (!isset($config['token_key'])) {
                throw new ConfigException('TokenAuthenticator需要配置token_key');
            }

            return new TokenAuthenticator(
                $config['token_key'],
                $config['timeout'] ?? 60 * 30,
                $config['auto_refresh'] ?? true,
                Container::get('cache'),
                Container::get('request')
            );
        });

        $authManager->registerAuthenticatorCreator('once', function ($config) {
            if (!isset($config['token_key'])) {
                throw new ConfigException('OnceAuthenticator需要配置token_key');
            }

            return new OnceAuthenticator(
                $config['token_key'],
                $config['timeout'] ?? 60 * 5,
                Container::get('cache'),
                Container::get('request')
            );
        });
    }

    /**
     * @inheritDoc
     */
    static protected function getConfig()
    {
        return config('auth.');
    }
}
