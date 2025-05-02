<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Validator;
use App\Models\Resource;

class ResourceController extends Controller
{
    public function index()
    {
        $resources = Resource::query()->paginate();
        return response()->json($resources);
    }

    public function show($id)
    {
        $resource = Resource::findOrFail($id);
        return response()->json($resource);
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'title' => 'required|string',
            'author' => 'required|string',
            'publication_date' => 'required|date',
            'genre' => 'required|string',
            'resource_type' => 'required|string',
            'isbn' => 'required|string',
            'summary' => 'required|string',
            'cover_image_url' => 'required|string',
            'metadata' => 'nullable|array',
        ]);
        $resource = Resource::create($data);
        return response()->json($resource, 201);
    }

    public function update(Request $request, $id)
    {
        $resource = Resource::findOrFail($id);
        $data = $request->validate([
            'title' => 'sometimes|required|string',
            'author' => 'sometimes|required|string',
            'publication_date' => 'sometimes|required|date',
            'genre' => 'sometimes|required|string',
            'resource_type' => 'sometimes|required|string',
            'isbn' => 'required|string',
            'summary' => 'sometimes|required|string',
            'cover_image_url' => 'sometimes|required|string',
            'metadata' => 'nullable|array',
        ]);
        $resource->update($data);
        return response()->json($resource);
    }

    public function destroy($id)
    {
        $resource = Resource::findOrFail($id);
        $resource->delete();
        return response()->json(null, 204);
    }
    public function getKetersediaan($resource_id, $start_date, $end_date){
        $resource = Resource::findOrFail($resource_id);
        $resource_item_count = $resource->items()
            ->whereNotIn('status', [ 'damaged', 'missing'])
            ->whereDoesntHave('resource_borrowings', function ($query) use ($start_date, $end_date){
                $query->where('start_date', '<=', $end_date)
                    ->where('end_date', '>=', $start_date);
            })
            ->count();
        return response()->json([
            'available' => $resource_item_count > 0,
            'quantity' => $resource_item_count
        ]);
    }
}
