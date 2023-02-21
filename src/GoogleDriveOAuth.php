<?php

namespace GoogleDriveOAuth;

use Illuminate\Support\Facades\Http;

class GoogleDriveOAuth
{
    public function redirect()
    {
        $config = config('services.google-drive'); 
        $uri = "https://accounts.google.com/o/oauth2/auth?scope=https://www.googleapis.com/auth/drive&response_type=code&access_type=offline&redirect_uri={$config['redirect_uri']}&client_id={$config['client_id']}";
        
        return redirect($uri);
    }

    public function callback()
    {
        $code = request()->query('code');
        $config = config('services.google-drive'); 

        $tokens = Http::post('https://accounts.google.com/o/oauth2/token', [
            'code' => $code,
            'client_id' => $config['client_id'],
            'client_secret' => $config['client_secret'],
            'redirect_uri' => $config['redirect_uri'],
            'grant_type' => 'authorization_code',
        ])->json();

        if (isset($tokens['error'])) {
            throw new GoogleDriveOAuthException($tokens);
        }
    
        $this->saveTokens($tokens);

        return $tokens['access_token'];
    }

    public function getAccessToken()
    {
        if (! $accessToken = session('google-drive.access_token')) {
            return;
        }

        if ($accessToken['expires_in'] < time()) {
            $accessToken = $this->refreshAccessToken();
        }

        return $accessToken['value'];
    }

    private function refreshAccessToken()
    {
        $config = config('services.google-drive');
        $refreshToken = session('google-drive.refresh_token'); 

        $tokens = Http::post('https://accounts.google.com/o/oauth2/token', [
            'refresh_token' => $refreshToken,
            'client_id' => $config['client_id'],
            'client_secret' => $config['client_secret'],
            'redirect_uri' => $config['redirect_uri'],
            'grant_type' => 'refresh_token',
        ])->json();

        if (isset($tokens['error'])) {
            throw new GoogleDriveOAuthException($tokens);
        }
    
        $this->saveTokens($tokens);

        return session('google-drive.access_token');
    }

    private function saveTokens($tokens)
    {
        session([
            'google-drive' => [
                'access_token' => [
                    'value' => $tokens['access_token'],
                    'expires_in' => time() + $tokens['expires_in'],
                ],
                'refresh_token' => $tokens['refresh_token'] ?? session('google-drive.refresh_token'),
            ]
        ]);
    }
}