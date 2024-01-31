<?php

namespace PinaOAuthClient;

use Pina\Access;
use Pina\App;
use Pina\Config;

class OAuthClient
{
    protected $resource = '';

    public function __construct($resource)
    {
        $this->resource = $resource;
    }

    public function register()
    {
        App::router()->register($this->resource, OAuthClientEndpoint::class);
        Access::permit($this->resource, 'public');
    }

    public function makeAuthorizeUrl($redirectUri = null)
    {

        $state = new RedirectState();
        $stateId = $state->set($redirectUri ?? $_SERVER['REQUEST_URI']);

        $query = [
            'client_id' => $this->getConfig('client_id'),
            'redirect_uri' => App::link($this->resource),
            'state' => $stateId
        ];

        return rtrim($this->getConfig('endpoint'), '/') . '/authorize?' . http_build_query($query);
    }

    public function authorize($code)
    {
        $params = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->getConfig('client_id'),
            'client_secret' => $this->getConfig('client_secret'),
            'code' => $code,
            'redirect_uri' => App::link($this->resource),
        ];

        $ch = curl_init(rtrim($this->getConfig('endpoint'), '/') . "/token");
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($info['http_code'] !== 200) {
            return null;
        }
        if (empty($result)) {
            return null;
        }
        $parsed = json_decode($result, true);
        if (empty($parsed['access_token'])) {
            return null;
        }
        return $parsed['access_token'];
    }

    public function getMyProfile($accessToken)
    {

        $ch = curl_init($this->getConfig('my_profile_endpoint'));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $accessToken
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($info['http_code'] !== 200) {
            return null;
        }

        if (empty($result)) {
            return null;
        }
        return json_decode($result, true);
    }

    protected function getConfig($name)
    {
        return Config::get($this->resource, $name);
    }

}
