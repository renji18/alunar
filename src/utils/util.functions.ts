import { PrismaService } from 'src/prisma.service';
import { Response } from 'express';

export async function findUserViaEmail(email: string, prisma: PrismaService) {
  const user = await prisma.user.findUnique({
    where: { email },
    include: { auth: true },
  });

  return user;
}

export async function customUnauthorizedError(response: Response) {
  response
    .status(401)
    .json({ error: "You don't have the authority to make this request" });
}

export async function customGoneError(response: Response, resource: string) {
  response.status(410).json({ error: `${resource} Not Found` });
}

export async function customError(response: Response, error: string) {
  response.status(401).json({ error });
}

export async function customSuccess(response: Response, data?: any) {
  response.status(201).json({ success: 'Request Successful', data });
}
