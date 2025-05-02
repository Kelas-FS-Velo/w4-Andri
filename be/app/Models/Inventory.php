<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Inventory extends Model
{
    protected $fillable = [
        'book_id',
        'location',
        'availability_status'
    ];

    public function book()
    {
        return $this->belongsTo(Book::class);
    }
}