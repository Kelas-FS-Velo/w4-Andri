<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ResourceBorrowing extends Model
{
    protected $fillable = [
        'resource_id',
        'resource_item_id',
        'user_id',
        'start_date',
        'end_date',
        'status',
    ];

    public function resource()
    {
        return $this->belongsTo(Resource::class);
    }
    public function resource_item()
    {
        return $this->belongsTo(ResourceItem::class);
    }
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
