<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        User::create([
            'name' => 'Admin User',
            'email' => 'admin@example.com',
            'password' => Hash::make('password'),
            'role' => 'admin',
        ]);

        User::create([
            'name' => 'Pustakawan User',
            'email' => 'pustakawan@example.com',
            'password' => Hash::make('password'),
            'role' => 'pustakawan',
        ]);

        User::create([
            'name' => 'Member User',
            'email' => 'member@example.com',
            'password' => Hash::make('password'),
            'role' => 'member',
        ]);
    }
}
