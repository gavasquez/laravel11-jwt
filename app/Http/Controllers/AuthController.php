<?php

namespace App\Http\Controllers;

use Exception;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json([
                'statusCode' => 401,
                'message' => 'Unauthorized'
            ], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'statusCode' => 200,
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    public function register(Request $request){


        try {

            $validator = Validator::make($request->all(), [
                "name" => 'required',
                "email" => 'required|unique:users,email|email|string',
                "password" => 'required|min:6'
            ]);

            $user = User::create(array_merge(array_merge(
                $validator->validated(),
                ['password' =>  bcrypt($request->password)]
            )));

            return response()->json([
                'statusCode' => 201,
                'message' => 'Usuario registrado correctamente',
                'data' => $user,
            ], 201);

        } catch (ValidationException $th) {
            return response()->json([
                'statusCode' => 400,
                'message' => 'Errores de validación',
                'data' => $th->errors(),
            ], 400);
        } catch(Exception $th) {
            return response()->json([
                'statusCode' => 500, // Internal Server Error
                'message' => 'Error al registrar usuario', // Error message
                'data' => $th->getMessage()
            ], 500);
        }

    }
}
