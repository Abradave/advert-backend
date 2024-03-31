<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisteRequest;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisteRequest $request){
        $user = User::create([
            "name" => $request->name,
            "email" => $request->emial,
            "password" => Hash::make($request->password),
        ]);
        return response()->json($user, 201);
    }
    public function login(LoginRequest $request){
        $user = User::where("email", $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(["message" => "incorrect user or password"], 401);
        }

        $token = $user->createToken("AuthToken")->plainTextToken;

        return response()->json(["token" => $token]);
    }
    public function logout(Request $request){
        $user = auth()->user();
        /** @disregard */
        $user->currentAccessToken() -> delete();
        return response()->noContent();
    }
}
