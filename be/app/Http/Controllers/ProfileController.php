<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function index()
    {
       return response()->json([
            'title' => 'Frontend Developer & AI Enthusiast',
            'name' => 'Andri',
            'description' => 'Saya merancang dan mengembangkan berbagai hal dengan desain yang indah dan sederhana. Saya sangat menyukai pekerjaan saya.',
            'avatar' => '/images/avatar-andri.png',
            'desk_image' => '/images/desk.png',
        ]);
        
    }
}
