#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
const int long_size = sizeof(long); //8
const int key = 2;

void encrypt(char *str)    //encrypt only letters reduced by 26 (number of letters in alphabet) if needed
{   int i;
    for (int i = 0; i < strlen(str); i++){
	if (str[i] >= 'A' && str[i]<= 'Z'){
		if ((str[i] + key) <= 'Z')
			str[i] += key;
		else{
			str[i] -= 26;
			str[i] += key;
			
		}
	}
	else if (str[i] >= 'a' && str[i] <= 'z'){
		if ((str[i] + key) <= 'z')
			str[i] += key;
		else{
			str[i] -= 26;
			str[i] += key;
		}
	}
    }
}
void decrypt(char *str)   //function to test funcionality
{   int i;
    int temp;
    for (int i = 0; i < strlen(str); i++){
	if (str[i] >= 'A' && str[i]<= 'Z'){
		if ((str[i] - key) >= 'A')
			str[i] -= key;
		else{
			str[i] += 26;
			str[i] += key;
		}
	}
	else if (str[i] >= 'a' && str[i] <= 'z'){
		if ((str[i] - key) >= 'a')
			str[i] -= key;
		else{
			str[i] += 26;
			str[i] -= key;
		}
	}
    }
}

void copydata(pid_t child, long addr,char *str, int len)
{   char *pointer;
    int i, j;
    union u {
            long val;
            char chars[long_size];  //ptrace peekdata returns long, so to evade casting  to *char there is an union
    }data;			
    i = 0;
    j = len / long_size; //which allows us to jump by 8bytes without risk
    pointer = str; //start of str where will be writed data from ptrace
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(pointer, data.chars, long_size); //copy data from child's process to str
        i++;
        pointer += long_size;
	//with every iteration addr and pointer move by 8 bytes 
    }
    j = len % long_size; //the rest of the data
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(pointer, data.chars, j);
    }
}


void putdata(pid_t child, long addr, char *str, int len)
{
    int i, j;
    char *pointer;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    pointer = str;
    while(i < j) {
        memcpy(data.chars, pointer, long_size); //copying from str to data.chars which (in form of long) will be pushed back to child's system call memory 
        ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
        i++;
        pointer += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, pointer, j);
        ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
    }
}



int main()
{
   pid_t child;
   child = fork();

   if(child == 0) {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execl("/bin/ls", "ls", NULL);
   }

   else {
      long orig_rax; //system call number
      long params[3]; //parameters on register
      int status; //status of child's exit
      char *str;
   	while(1)
   	{
        	wait(&status);
        	if(WIFEXITED(status))
			break;		//check if child is terminated normally (working asynchronically)

        	orig_rax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, NULL); //start of tracing and checking system call number which is on ORIG_RAX register

        	if(orig_rax == SYS_write){  //checking if child made accurate system call
	 
               		params[0] = ptrace(PTRACE_PEEKUSER, child, 8 * RDI, NULL);
               		params[1] = ptrace(PTRACE_PEEKUSER, child, 8 * RSI, NULL); //RSI - address of child's system call
               		params[2] = ptrace(PTRACE_PEEKUSER, child, 8 * RDX, NULL); //RDX - length of write's char's array (i think)

               		str = (char *)malloc((params[2] + 1)* sizeof(char)); //allocate memory for child's data from write system call + '\0'
               		copydata(child, params[1], str, params[2]);
	   
               		encrypt(str);
	       		//decrypt(str);
               		putdata(child, params[1], str, params[2]);
		}	   
        ptrace(PTRACE_SYSCALL, child, NULL, NULL); //similar to PTRACE_CONT which wakes up child process
     }
  }
  return 0;
}
