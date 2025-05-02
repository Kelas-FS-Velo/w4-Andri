<?php

namespace Database\Seeders;

use App\Models\Inventory;
use Illuminate\Database\Seeder;

class InventorySeeder extends Seeder
{
    public function run(): void
    {
        $inventories = [
            ['book_id' => 1, 'location' => 'Shelf 1', 'availability_status' => true],
            ['book_id' => 2, 'location' => 'Shelf 2', 'availability_status' => true],
            ['book_id' => 3, 'location' => 'Shelf 3', 'availability_status' => false],
            ['book_id' => 4, 'location' => 'Shelf 4', 'availability_status' => true],
            ['book_id' => 5, 'location' => 'Shelf 5', 'availability_status' => false],
            ['book_id' => 6, 'location' => 'Shelf 6', 'availability_status' => true],
            ['book_id' => 7, 'location' => 'Shelf 7', 'availability_status' => true],
            ['book_id' => 8, 'location' => 'Shelf 8', 'availability_status' => false],
            ['book_id' => 9, 'location' => 'Shelf 9', 'availability_status' => true],
            ['book_id' => 10, 'location' => 'Shelf 10', 'availability_status' => true]
        ];

        foreach ($inventories as $inventoryData) {
            Inventory::create($inventoryData);
        }
    }
}