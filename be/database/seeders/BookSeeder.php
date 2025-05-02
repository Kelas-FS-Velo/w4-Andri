<?php

namespace Database\Seeders;

use App\Models\Book;
use Illuminate\Database\Seeder;

class BookSeeder extends Seeder
{
    public function run(): void
    {
        $books = [
            [
                'title' => 'The Great Gatsby',
                'author' => 'F. Scott Fitzgerald',
                'isbn' => '9780743273565',
                'publication_year' => 1925,
                'description' => 'A story of the fabulously wealthy Jay Gatsby and his love for the beautiful Daisy Buchanan.',
                'cover_image' => 'great_gatsby.jpg'
            ],
            [
                'title' => 'To Kill a Mockingbird',
                'author' => 'Harper Lee',
                'isbn' => '9780061120084',
                'publication_year' => 1960,
                'description' => 'The story of racial injustice and the loss of innocence in the American South.',
                'cover_image' => 'mockingbird.jpg'
            ],
            [
                'title' => '1984',
                'author' => 'George Orwell',
                'isbn' => '9780451524935',
                'publication_year' => 1949,
                'description' => 'A dystopian novel set in a totalitarian society ruled by the Party and its leader Big Brother.',
                'cover_image' => '1984.jpg'
            ],
            [
                'title' => 'Pride and Prejudice',
                'author' => 'Jane Austen',
                'isbn' => '9780141439518',
                'publication_year' => 1813,
                'description' => 'The story of Elizabeth Bennet and her relationship with the proud Mr. Darcy.',
                'cover_image' => 'pride_prejudice.jpg'
            ],
            [
                'title' => 'The Catcher in the Rye',
                'author' => 'J.D. Salinger',
                'isbn' => '9780316769488',
                'publication_year' => 1951,
                'description' => 'The story of Holden Caulfield and his experiences in New York City.',
                'cover_image' => 'catcher_rye.jpg'
            ],
            [
                'title' => 'The Hobbit',
                'author' => 'J.R.R. Tolkien',
                'isbn' => '9780547928227',
                'publication_year' => 1937,
                'description' => 'The adventure of Bilbo Baggins and his quest to reclaim the Lonely Mountain.',
                'cover_image' => 'hobbit.jpg'
            ],
            [
                'title' => 'The Lord of the Rings',
                'author' => 'J.R.R. Tolkien',
                'isbn' => '9780544003415',
                'publication_year' => 1954,
                'description' => 'The epic tale of the War of the Ring and the quest to destroy the One Ring.',
                'cover_image' => 'lotr.jpg'
            ],
            [
                'title' => 'The Chronicles of Narnia',
                'author' => 'C.S. Lewis',
                'isbn' => '9780064471190',
                'publication_year' => 1950,
                'description' => 'The magical adventures of children in the land of Narnia.',
                'cover_image' => 'narnia.jpg'
            ],
            [
                'title' => 'The Alchemist',
                'author' => 'Paulo Coelho',
                'isbn' => '9780062315007',
                'publication_year' => 1988,
                'description' => 'The story of Santiago and his journey to find his personal legend.',
                'cover_image' => 'alchemist.jpg'
            ],
            [
                'title' => 'The Little Prince',
                'author' => 'Antoine de Saint-Exupéry',
                'isbn' => '9780156012195',
                'publication_year' => 1943,
                'description' => 'The story of a young prince who travels from planet to planet.',
                'cover_image' => 'little_prince.jpg'
            ]
        ];

        foreach ($books as $bookData) {
            Book::create($bookData);
        }
    }
}