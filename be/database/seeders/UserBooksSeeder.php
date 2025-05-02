<?php

namespace Database\Seeders;

use App\Models\UserBook;
use Illuminate\Database\Seeder;

class UserBooksSeeder extends Seeder
{
    public function run(): void
    {
        $userBooks = [
            ['user_id' => 1, 'book_id' => 1],
            ['user_id' => 1, 'book_id' => 2],
            ['user_id' => 1, 'book_id' => 3],
            ['user_id' => 2, 'book_id' => 4],
            ['user_id' => 2, 'book_id' => 5],
            ['user_id' => 2, 'book_id' => 6],
            ['user_id' => 3, 'book_id' => 7],
            ['user_id' => 3, 'book_id' => 8],
            ['user_id' => 3, 'book_id' => 9],
            ['user_id' => 4, 'book_id' => 10],
            ['user_id' => 4, 'book_id' => 1],
            ['user_id' => 4, 'book_id' => 2],
            ['user_id' => 5, 'book_id' => 3],
            ['user_id' => 5, 'book_id' => 4],
            ['user_id' => 5, 'book_id' => 5],
            ['user_id' => 1, 'book_id' => 6],
            ['user_id' => 2, 'book_id' => 7],
            ['user_id' => 3, 'book_id' => 8],
            ['user_id' => 4, 'book_id' => 9],
            ['user_id' => 5, 'book_id' => 10],
            ['user_id' => 1, 'book_id' => 4],
            ['user_id' => 2, 'book_id' => 5],
            ['user_id' => 3, 'book_id' => 6],
            ['user_id' => 4, 'book_id' => 7],
            ['user_id' => 5, 'book_id' => 8]
        ];

        foreach ($userBooks as $userBookData) {
            UserBook::create($userBookData);
        }
    }
}