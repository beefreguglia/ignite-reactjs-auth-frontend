import axios, { AxiosError } from 'axios';
import { parseCookies, setCookie } from 'nookies';
import { signOut } from '../contexts/AuthContex';
import { AuthTokenError } from '../errors/AuthTokenError';


let isRefreshing = false;
let failedRequestsQueue: { onSucces: (token: string) => void; onFailure: (error: AxiosError<any, any>) => void; }[] = [];

export function setupAPIClient(ctx = undefined) {
  let cookies = parseCookies(ctx);

  const api = axios.create({
    baseURL: 'http://localhost:3333',
    headers: {
      Authorization: `Bearer ${cookies['nextauth.token']}`
    }
  })
  
  api.interceptors.response.use(response => {
    return response;
  }, (error: AxiosError) => {
    if(error.response?.status === 401) {
      if(error.response.data?.code === 'token.expired'){ 
        cookies = parseCookies(ctx);
        const { 'nextauth.refreshToken' : refreshToken } = cookies;
        const originalConfig = error.config;
  
        if (!isRefreshing) {
          isRefreshing = true;
  
          api.post('/refresh', {
            refreshToken,
          }).then(response => {
            const { token } = response.data;
            setCookie(ctx, 'nextauth.token', token, {
              maxAge: 60 * 60 * 25 * 30, //30 dias
              path: '/',
            });
            setCookie(ctx,'nextauth.refreshToken', response.data.refreshToken, {
              maxAge: 60 * 60 * 25 * 30, //30 dias
              path: '/',
            });
            api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
          
            failedRequestsQueue.forEach(request => request.onSucces(token));
            failedRequestsQueue = []
          }).catch(err => {
            failedRequestsQueue.forEach(request => request.onFailure(err))
            failedRequestsQueue = []
  
            if(process.browser) {
              signOut();
            }
          }).finally(() => {
            isRefreshing = false;
          });
        }
  
        return new Promise((resolve, reject) => {
          failedRequestsQueue.push({
            onSucces: (token: string) => {
              if(!originalConfig?.headers) {
                return;
              }
              originalConfig.headers['Authorization'] = `Bearer ${token}`;
              resolve(api(originalConfig));
            },
            onFailure: (error: AxiosError) => {
              reject(error);
            }
          })
        });
      } else {
        if(process.browser) {
          signOut()
        } else {
          return Promise.reject(new AuthTokenError());
        }
      }
    }
    return Promise.reject(error);
  }); 
  return api;
}