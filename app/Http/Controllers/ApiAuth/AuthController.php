<?php

namespace App\Http\Controllers\ApiAuth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use App\Validators\MyValidators;

class AuthController extends Controller
{
    public function register(Request $request): \Illuminate\Http\JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/',
            'username' => 'required|string|min:3|max:20|alpha_dash', // Validación personalizada
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors()->messages(),
            ], 422);
        }

        $user = User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => bcrypt($request->input('password')),
            'username' => $request->input('username'),
        ]);

        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
            'success' => true,
            'data' => [
                'user' => $user,
                'token' => $token,
            ],
        ], 201);
    }

    public function login(Request $request): \Illuminate\Http\JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Por favor, proporciona un correo electrónico y contraseña válidos.',
                'errors' => $validator->errors()->all()
            ], 422);
        }

        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken('authToken')->plainTextToken;

            return response()->json([
                'success' => true,
                'data' => [
                    'user' => $user,
                    'access_token' => $token, // Cambiado de 'token' a 'access_token' para mayor claridad
                    'token_type' => 'Bearer', // Agregado el tipo de token
                    'expires_in' => $user->tokens()->first()->expires_at->diffInSeconds(now()), // Calcula la duración del token
                    'message' => 'Acceso concedido.',
                ],
            ], 200);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Credenciales incorrectas. El correo electrónico o la contraseña no coinciden.',
            ], 401);
        }
    }



    public function logout(Request $request): \Illuminate\Http\JsonResponse
    {
        $request->user()->tokens()->delete();

        return response()->json([
            'success' => true,
            'message' => 'Has cerrado sesión exitosamente.',
        ]);
    }
public function users(): \Illuminate\Http\JsonResponse
{
    $users = User::all();
    return response()->json(['users' => $users], 200);
}
}
