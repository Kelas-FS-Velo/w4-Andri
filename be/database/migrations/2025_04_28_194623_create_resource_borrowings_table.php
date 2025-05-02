<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('resource_borrowings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('resource_id');
            $table->foreignId('resource_item_id');
            $table->foreignId('user_id');
            $table->date('start_date');
            $table->date('end_date');
            $table->enum('status', ['pending', 'approved', 'borrowed', 'returned'])->default('pending');
            $table->softDeletes();
            $table->timestamps();
        });
    }
    
    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('resource_borrowings');
    }
};
