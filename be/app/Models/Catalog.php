<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use App\Models\Book;

class Catalog extends Model
{
    protected $fillable = [
        'resource_type',
        'call_number',
        'subjects',
        'book_id'
    ];

    public function book()
    {
        return $this->belongsTo(Book::class);
    }
}
