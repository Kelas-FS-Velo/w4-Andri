<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Models\Resource;
use App\Http\Controllers\ResourceController;
use Illuminate\Foundation\Testing\RefreshDatabase;

class GetKetersediaanTest extends TestCase
{
    use RefreshDatabase;
    /**
     * A basic unit test example.
     */
    public function test_get_ketersediaan_available()
    {
        $resource_id = 1;
        $start_date = '2025-05-01';
        $end_date = '2025-05-03';

        $resource = Resource::create([
            'id' => $resource_id,
            'title' => 'Test Title',
            'author' => 'Test Author',
            'publication_date' => '2025-01-01',
            'genre' => 'Test Genre',
            'summary' => 'Test Summary',
            'cover_image_url' => 'http://example.com/image.jpg',
        ]);
        $resource->items()->create([
            'status' => 'available',
            'item_number' => '1',
        ]);
        $resource->items()->create([
            'status' => 'available',
            'item_number' => '2',
        ]);
        $resource->items()->create([
            'status' => 'available',
            'item_number' => '3',
        ]);
        $book4 = $resource->items()->create([
            'status' => 'available',
            'item_number' => '4',
        ]);

        $book4->resource_borrowings()->create([
            'resource_id' => $resource_id,
            'resource_item_id' => $book4->id,
            'user_id' => 1,
            'start_date' => '2025-05-01',
            'end_date' => '2025-05-25',
            'status' => 'borrowed',
        ]);

        $controller = new ResourceController();
        $response = $controller->getKetersediaan($resource_id, $start_date, $end_date);
        $data = $response->getData(true);
        $this->assertEquals(['available' => true, 'quantity' => 3], $data);
    }

    public function test_get_ketersediaan_unavailable()
    {
        $resource_id = 2;
        $start_date = '2025-05-01';
        $end_date = '2025-05-03';

        $resource = Resource::create([
            'id' => $resource_id,
            'title' => 'Test Title',
            'author' => 'Test Author',
            'publication_date' => '2025-01-01',
            'genre' => 'Test Genre',
            'summary' => 'Test Summary',
            'cover_image_url' => 'http://example.com/image.jpg',
        ]);
        $book4 = $resource->items()->create([
            'status' => 'available',
            'item_number' => '4',
        ]);

        $book4->resource_borrowings()->create([
            'resource_id' => $resource_id,
            'resource_item_id' => $book4->id,
            'user_id' => 1,
            'start_date' => '2025-05-01',
            'end_date' => '2025-05-25',
            'status' => 'borrowed',
        ]);

        $controller = new ResourceController();
        $response = $controller->getKetersediaan($resource_id, $start_date, $end_date);
        $data = $response->getData(true);
        $this->assertEquals(['available' => false, 'quantity' => 0], $data);
    }
}
