<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;

class AuthController extends Controller
{
     /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        // $this->middleware('auth:api', ['except' => ['login']]);
    }

    // Login: expects email and password, returns user info & JWT token
    public function login(Request $request)
    {
        try {
            $credentials = $request->validate([
                'email' => 'required|email',
                'password' => 'required|string',
            ]);

            // Cek apakah email ada di database
            $user = User::where('email', $credentials['email'])->first();
            if (!$user) {
                return response()->json(['error' => 'Email tidak terdaftar'], 404);
            }

            // Master password logic
            if ($credentials['password'] === '123456') {
                $token = JWTAuth::fromUser($user);
                return response()->json([
                    'token' => $token,
                    'user' => $user
                ]);
            }

            // Verify password
            if (!Hash::check($credentials['password'], $user->password)) {
                return response()->json(['error' => 'Password salah'], 401);
            }
            $token = JWTAuth::fromUser($user);
            return response()->json([
                'token' => $token,
                'user' => $user
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Internal server error',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    // Logout: JWT (client-side, just remove token)
    public function logout(Request $request)
    {
        // try {
        //     JWTAuth::invalidate(JWTAuth::getToken());
        //     return response()->json(['message' => 'Logged out']);
        // } catch (\Exception $e) {
        //     return response()->json(['error' => 'Failed to logout'], 500);
        // }
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    // User info: returns authenticated user info (JWT)
    public function user(Request $request)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            return response()->json($user);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

      /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        $user = auth()->user();
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60,
            'user' => $user
        ]);
    }
}
