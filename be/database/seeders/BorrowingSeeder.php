<?php

namespace Database\Seeders;

use App\Models\Borrowing;
use Illuminate\Database\Seeder;

class BorrowingSeeder extends Seeder
{
    public function run(): void
    {
        $borrowings = [
            ['user_id' => 1, 'book_id' => 1, 'borrowed_at' => '2025-03-01 10:00:00', 'due_at' => '2025-03-15 10:00:00', 'returned_at' => '2025-03-10 10:00:00'],
            ['user_id' => 2, 'book_id' => 3, 'borrowed_at' => '2025-03-05 14:00:00', 'due_at' => '2025-03-19 14:00:00', 'returned_at' => null],
            ['user_id' => 3, 'book_id' => 5, 'borrowed_at' => '2025-03-02 09:00:00', 'due_at' => '2025-03-16 09:00:00', 'returned_at' => '2025-03-12 09:00:00'],
            ['user_id' => 4, 'book_id' => 7, 'borrowed_at' => '2025-03-03 11:00:00', 'due_at' => '2025-03-17 11:00:00', 'returned_at' => null],
            ['user_id' => 5, 'book_id' => 9, 'borrowed_at' => '2025-03-04 13:00:00', 'due_at' => '2025-03-18 13:00:00', 'returned_at' => '2025-03-14 13:00:00'],
            ['user_id' => 1, 'book_id' => 2, 'borrowed_at' => '2025-03-06 10:00:00', 'due_at' => '2025-03-20 10:00:00', 'returned_at' => null],
            ['user_id' => 2, 'book_id' => 4, 'borrowed_at' => '2025-03-07 14:00:00', 'due_at' => '2025-03-21 14:00:00', 'returned_at' => '2025-03-16 14:00:00'],
            ['user_id' => 3, 'book_id' => 6, 'borrowed_at' => '2025-03-08 09:00:00', 'due_at' => '2025-03-22 09:00:00', 'returned_at' => null],
            ['user_id' => 4, 'book_id' => 8, 'borrowed_at' => '2025-03-09 11:00:00', 'due_at' => '2025-03-23 11:00:00', 'returned_at' => '2025-03-18 11:00:00'],
            ['user_id' => 5, 'book_id' => 10, 'borrowed_at' => '2025-03-10 13:00:00', 'due_at' => '2025-03-24 13:00:00', 'returned_at' => null],
            ['user_id' => 1, 'book_id' => 3, 'borrowed_at' => '2025-03-11 10:00:00', 'due_at' => '2025-03-25 10:00:00', 'returned_at' => '2025-03-20 10:00:00'],
            ['user_id' => 2, 'book_id' => 5, 'borrowed_at' => '2025-03-12 14:00:00', 'due_at' => '2025-03-26 14:00:00', 'returned_at' => null],
            ['user_id' => 3, 'book_id' => 7, 'borrowed_at' => '2025-03-13 09:00:00', 'due_at' => '2025-03-27 09:00:00', 'returned_at' => '2025-03-22 09:00:00'],
            ['user_id' => 4, 'book_id' => 9, 'borrowed_at' => '2025-03-14 11:00:00', 'due_at' => '2025-03-28 11:00:00', 'returned_at' => null],
            ['user_id' => 5, 'book_id' => 1, 'borrowed_at' => '2025-03-15 13:00:00', 'due_at' => '2025-03-29 13:00:00', 'returned_at' => '2025-03-24 13:00:00'],
            ['user_id' => 1, 'book_id' => 4, 'borrowed_at' => '2025-03-16 10:00:00', 'due_at' => '2025-03-30 10:00:00', 'returned_at' => null],
            ['user_id' => 2, 'book_id' => 6, 'borrowed_at' => '2025-03-17 14:00:00', 'due_at' => '2025-03-31 14:00:00', 'returned_at' => '2025-03-26 14:00:00'],
            ['user_id' => 3, 'book_id' => 8, 'borrowed_at' => '2025-03-18 09:00:00', 'due_at' => '2025-04-01 09:00:00', 'returned_at' => null],
            ['user_id' => 4, 'book_id' => 10, 'borrowed_at' => '2025-03-19 11:00:00', 'due_at' => '2025-04-02 11:00:00', 'returned_at' => '2025-03-28 11:00:00'],
            ['user_id' => 5, 'book_id' => 2, 'borrowed_at' => '2025-03-20 13:00:00', 'due_at' => '2025-04-03 13:00:00', 'returned_at' => null]
        ];

        foreach ($borrowings as $borrowingData) {
            Borrowing::create($borrowingData);
        }
    }
}