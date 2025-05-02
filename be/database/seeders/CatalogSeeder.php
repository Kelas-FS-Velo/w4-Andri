<?php

namespace Database\Seeders;

use App\Models\Catalog;
use Illuminate\Database\Seeder;

class CatalogSeeder extends Seeder
{
    public function run(): void
    {
        $catalogs = [
            ['resource_type' => 'Book', 'call_number' => 'C1234', 'subjects' => json_encode(['Fiction', 'Classic']), 'book_id' => 1],
            ['resource_type' => 'Book', 'call_number' => 'C5678', 'subjects' => json_encode(['Fiction', 'Social Issues']), 'book_id' => 2],
            ['resource_type' => 'Book', 'call_number' => 'C9101', 'subjects' => json_encode(['Fiction', 'Dystopian']), 'book_id' => 3],
            ['resource_type' => 'Book', 'call_number' => 'C1121', 'subjects' => json_encode(['Fiction', 'Romance']), 'book_id' => 4],
            ['resource_type' => 'Book', 'call_number' => 'C3141', 'subjects' => json_encode(['Fiction', 'Coming of Age']), 'book_id' => 5],
            ['resource_type' => 'Book', 'call_number' => 'C5161', 'subjects' => json_encode(['Fiction', 'Fantasy']), 'book_id' => 6],
            ['resource_type' => 'Book', 'call_number' => 'C7181', 'subjects' => json_encode(['Fiction', 'Adventure']), 'book_id' => 7],
            ['resource_type' => 'Book', 'call_number' => 'C9202', 'subjects' => json_encode(['Fiction', 'Children\'s Literature']), 'book_id' => 8],
            ['resource_type' => 'Book', 'call_number' => 'C1222', 'subjects' => json_encode(['Fiction', 'Philosophical']), 'book_id' => 9],
            ['resource_type' => 'Book', 'call_number' => 'C3242', 'subjects' => json_encode(['Fiction', 'Fantasy']), 'book_id' => 10]
        ];

        foreach ($catalogs as $catalogData) {
            Catalog::create($catalogData);
        }
    }
}