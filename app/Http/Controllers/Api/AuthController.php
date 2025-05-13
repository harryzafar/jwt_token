<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Models\RefreshToken;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Carbon\Carbon;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(Request $request)
    { 
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:50',
            'email' => 'required|string|email|max:50|unique:users',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $accessToken = auth()->login($user);

        $refreshToken = $this->createRefreshToken($user->id);

        return $this->respondWithTokens($accessToken, $refreshToken, $user, 'User registered successfully');
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'errors' => $validator->errors(),
            ], 422);
        }

        $credentials = $request->only('email', 'password');

        if (!$accessToken = auth()->attempt($credentials)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }

        $user = auth()->user();

        $refreshToken = $this->createRefreshToken($user->id);

        return $this->respondWithTokens($accessToken, $refreshToken, $user, 'Login successful');
    }

    public function logout()
    {

        // Optionally, delete the refresh token on logout
        RefreshToken::where('user_id', auth()->id())->delete();

        auth()->logout();

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh(Request $request)
    {
        $request->validate([
            'refresh_token' => 'required|string',
        ]);

        // Hash the incoming token to match the stored hash
        $hashedToken = hash('sha256', $request->refresh_token);

        $refreshToken = RefreshToken::where('token', $hashedToken)
            ->where('expires_at', '>', now())
            ->first();

        if (!$refreshToken) {
            return response()->json(['error' => 'Invalid or expired refresh token'], 401);
        }

        // Get the user and generate a new access token
        $user = User::find($refreshToken->user_id);
        $newAccessToken = auth()->login($user);

        return response()->json([
            'status' => 'success',
            'access_token' => $newAccessToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
        ]);
    }

    public function me()
    {
       
        return response()->json([
            'status' => 'success',
            'user' => auth()->user()
        ]);
    }

    protected function respondWithTokens($accessToken, $refreshToken, $user, $message = null)
    {
        return response()->json([
            'status' => 'success',
            'message' => $message,
            'user' => $user,
            'authorisation' => [
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60,
            ]
        ]);
    }

    private function createRefreshToken($userId)
    {
        // Optional: Invalidate old tokens
        RefreshToken::where('user_id', $userId)->delete();

        $token = Str::random(64); // Random secure string
        $expiresAt = Carbon::now()->addDays(7); // 7-day token, adjust as needed

        RefreshToken::create([
            'user_id' => $userId,
            'token' => hash('sha256', $token), // Always store hashed version
            'expires_at' => $expiresAt,
        ]);

        return $token;
    }
}
