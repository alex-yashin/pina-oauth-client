<?php

namespace PinaOAuthClient;

use Pina\Http\Endpoint;
use Pina\Response;

abstract class OAuthClientEndpoint extends Endpoint
{

    abstract protected function loginAs(array $profile);

    public function index()
    {
        $code = $this->query()->get('code');
        if ($code) {
            return $this->authorize($code);
        }

        $client = new OAuthClient($this->location->resource('@'));
        return Response::found($client->makeAuthorizeUrl('/'));
    }

    protected function authorize($code)
    {
        $state = new RedirectState();
        $redirectUri = $state->get($this->query()->get('state'));
        if (empty($redirectUri)) {
            //гугл индексирует перенаправление на oauth/authorize и иногда по ссылке приходят из поисковой системы
            //в этом случае internalError делать нельзя, так как пользователь сразу же после перехода из поисковика увидит 500
            //вместо перехода на авторизацию
            return Response::found("/");
        }

        $client = new OAuthClient($this->location->resource('@'));
        $accessToken = $client->authorize($code);

        if (empty($accessToken)) {
            return Response::internalError();
        }

        $profile = $client->getMyProfile($accessToken);
        if (empty($profile)) {
            return Response::forbidden();
        }

        $this->loginAs($profile);

        if ($this->isSecureUri($redirectUri)) {
            return Response::found($redirectUri);
        }

        return Response::found('/');
    }

    protected function isSecureUri($redirectUri): bool
    {
        return true;
    }

}
