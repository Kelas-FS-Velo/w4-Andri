<?php

namespace Database\Seeders;

use App\Models\Recommendation;
use Illuminate\Database\Seeder;

class RecommendationSeeder extends Seeder
{
    public function run(): void
    {
        $recommendations = [
            ['user_id' => 1, 'book_id' => 1, 'recommendation_score' => 0.1],
            ['user_id' => 2, 'book_id' => 3, 'recommendation_score' => 0.2],
            ['user_id' => 3, 'book_id' => 5, 'recommendation_score' => 0.3],
            ['user_id' => 4, 'book_id' => 7, 'recommendation_score' => 0.4],
            ['user_id' => 5, 'book_id' => 9, 'recommendation_score' => 0.5],
            ['user_id' => 1, 'book_id' => 2, 'recommendation_score' => 0.1],
            ['user_id' => 2, 'book_id' => 4, 'recommendation_score' => 0.2],
            ['user_id' => 3, 'book_id' => 6, 'recommendation_score' => 0.3],
            ['user_id' => 4, 'book_id' => 8, 'recommendation_score' => 0.4],
            ['user_id' => 5, 'book_id' => 10, 'recommendation_score' => 0.5],
            ['user_id' => 1, 'book_id' => 3, 'recommendation_score' => 0.1],
            ['user_id' => 2, 'book_id' => 5, 'recommendation_score' => 0.2],
            ['user_id' => 3, 'book_id' => 7, 'recommendation_score' => 0.3],
            ['user_id' => 4, 'book_id' => 9, 'recommendation_score' => 0.4],
            ['user_id' => 5, 'book_id' => 1, 'recommendation_score' => 0.5]
        ];

        foreach ($recommendations as $recommendationData) {
            Recommendation::create($recommendationData);
        }
    }
}