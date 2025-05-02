<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use App\Models\Inventory;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Book extends Model
{
    use HasFactory;
    protected $fillable = [
        'title',
        'author',
        'isbn',
        'publication_year',
        'description',
        'cover_image'
    ];

    public function inventory()
    {
        return $this->hasMany(Inventory::class);
    }

    public function users()
    {
        return $this->belongsToMany(User::class, 'user_books');
    }
}
