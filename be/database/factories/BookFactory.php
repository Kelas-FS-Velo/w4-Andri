<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;

class BookFactory extends Factory
{
    public function definition()
    {
        return [
            'title' => $this->faker->sentence,
            'author' => $this->faker->name,
            'isbn' => $this->faker->isbn13,
            'publication_year' => $this->faker->year,
            'description' => $this->faker->paragraph,
            'cover_image' => $this->faker->imageUrl,
        ];
    }
}
