<?php

namespace App\Validators;

use Illuminate\Support\Facades\Validator;

class MyValidators
{
    public static function validateUsername($username): bool
    {
        return Validator::make(['username' => $username], [
            'username' => 'required|string|min:3|max:20|alpha_dash',
        ])->passes();
    }
}
