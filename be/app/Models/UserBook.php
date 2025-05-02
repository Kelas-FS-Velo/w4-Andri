<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class UserBook extends Model
{
    use HasFactory, SoftDeletes;

    protected $table = 'user_books';

    protected $fillable = [
        'user_id',
        'book_id',
    ];
}
