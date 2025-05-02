<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;

class AuthController extends Controller
{
    // Login: expects email and password, returns user info & JWT token
    public function login(Request $request)
    {
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
            // Generate token manual untuk user ini
            $token = JWTAuth::fromUser($user);
            return response()->json([
                'token' => $token,
                'user' => $user
            ]);
        }

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return response()->json([
            'token' => $token,
            'user' => auth()->user()
        ]);
    }

    // Logout: JWT (client-side, just remove token)
    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Logged out']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to logout'], 500);
        }
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
}
