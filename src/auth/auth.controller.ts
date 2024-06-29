import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginDto, RegisterDto } from 'src/dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern({ cmd: 'auth.register.user' })
  registerUser(@Payload() registerUserDto: RegisterDto) {
    return this.authService.registerUser(registerUserDto);
  }

  @MessagePattern({ cmd: 'auth.login.user' })
  loginUser(@Payload() loginUserDto: LoginDto) {
    return this.authService.loginUser(loginUserDto);
  }

  @MessagePattern({ cmd: 'auth.verify.user' })
  verifyUser(@Payload() token: string) {
    return this.authService.verifyToken(token);
  }
}
