<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Abstract base model for all resources.
 *
 * @property int $id
 * @property string $title
 * @property string $author
 * @property string $publication_date
 * @property string $genre
 * @property string $summary
 * @property string $cover_image_url
 * @property array|null $metadata
 * @property string $created_at
 * @property string $updated_at
 */
class Resource extends Model
{
    protected $table = 'resources';
    protected $guarded = [];
    protected $casts = [
        'metadata' => 'array',
        'publication_date' => 'date',
    ];
    public function items()
    {
        return $this->hasMany(ResourceItem::class);
    }
}
