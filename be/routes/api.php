<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\ResourceController;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/


// Route::post('/login', [AuthController::class, 'login']);
// Route::middleware('jwt.auth')->post('/logout', [AuthController::class, 'logout']);
// Route::middleware('jwt.auth')->get('/user', [AuthController::class, 'user']);

Route::group(['middleware' => 'api','prefix' => 'auth'], function ($router) {
    
    Route::post('login', [AuthController::class, 'login']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('me', [AuthController::class, 'me']);
});

Route::get('/profile', [ProfileController::class, 'index']);

Route::get('/resources', [ResourceController::class, 'index']); // List all resources
Route::post('/resources', [ResourceController::class, 'store']); // Create new resource
Route::get('/resources/{resource}', [ResourceController::class, 'show']); // Show single resource
Route::put('/resources/{resource}', [ResourceController::class, 'update']); // Update resource
Route::patch('/resources/{resource}', [ResourceController::class, 'update']); // Partial update
Route::delete('/resources/{resource}', [ResourceController::class, 'destroy']); // Delete resource
