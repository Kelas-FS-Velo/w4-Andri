<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ResourceItem extends Model
{
    //
    protected $fillable = [
        'resource_id',
        'item_number',
        'status',
    ];
    public function resource()
    {
        return $this->belongsTo(Resource::class);
    }
    public function resource_borrowings()
{
    return $this->hasMany(ResourceBorrowing::class, 'resource_item_id');
}
    public function borrowing()
    {
        return $this->belongsTo(ResourceBorrowing::class);
    }
}
