<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        if (!User::where('email', 'test@example.com')->exists()) {
            User::factory()->create([
                'name' => 'Test User',
                'email' => 'test@example.com',
            ]);
        }

        $this->call([
            UserSeeder::class,
            BookSeeder::class,
            CatalogSeeder::class,
            InventorySeeder::class,
            RecommendationSeeder::class,
            BorrowingSeeder::class,
            UserBooksSeeder::class,
        ]);
    }
}
