package technology_store;

import java.util.Scanner;

public class boss extends humans {
	public String name_or_brand_name;
	protected String superscription;
	
	public boss(String name_or_brand_name, String superscription) {
		this.name_or_brand_name = name_or_brand_name;
		this.superscription = superscription;
	}
	
	public String question() {
		System.out.print("Do you want to see your storehouse? Y/N ");
		Scanner input = new Scanner(System.in);
		String a = input.next();
		
		while (!(a.equals("Y") || a.equals("y") || a.equals("N") || a.equals("n"))) {
			System.out.println("Invalid entry!");
			System.out.print("Do you want to see your storehouse? Y/N ");
			a = input.next();
		}
		
		if (a.equals("Y") || a.equals("y")) {
			return a;
		}
		
		else if (a.equals("N") || a.equals("n")) {
			System.out.print("");
		}
		return a;
	}
	
	public int[] change() {
		int x = 1;
		Scanner input = new Scanner(System.in);
		System.out.println("Which one do you want to change? 1/2/3/4/5/6");
		System.out.println("If you don't want change anything press: 9!");
		System.out.println("If you don't want change anything else press: 0!");
		int[] change = {0,0,0,0,0,0,0};
		int[] num1 = {0,0,0,0,0,0};
		while(x==1) {

			int num = input.nextInt();
			
			if (num==1 && num1[0]==0) {
				change[0]+=1;
				num1[0]=1;
			}
			
			else if (num==1 && num1[0]==1) {
				System.out.println("You already chose it!");
			}
		
			else if (num==2 && num1[1]==0) {
				change[1]+=1;
				num1[1]=1;
			}
			
			else if (num==2 && num1[1]==1) {
				System.out.println("You already chose it!");
			}
			
			else if (num==3 && num1[2]==0) {
				change[2]+=1;
				num1[2]=1;
			}
			
			else if (num==3 && num1[2]==1) {
				System.out.println("You already chose it!");
			}
			
			else if (num==4 && num1[3]==0) {
				change[3]+=1;
				num1[3]=1;
			}
			
			else if (num==4 && num1[3]==1) {
				System.out.println("You already chose it!");
			}
			
			else if (num==5 && num1[4]==0) {
				change[4]+=1;
				num1[4]=1;
			}
			
			else if (num==5 && num1[4]==1) {
				System.out.println("You already chose it!");
			}
			
			else if (num==6 && num1[5]==0) {
				change[5]+=1;
				num1[5]=1;
			}
			
			else if (num==6 && num1[5]==1) {
				System.out.println("You already chose it!");
			}
				
			else if (num==0) {
				x=0;
			}
			
			else if (num==9) {
				change[6]=6;
				x=0;
			}
			
			else {
				System.out.println("Invalid entry!");
				System.out.println("Which one do you want to change? 1/2/3/4/5/6");
				System.out.println("If you don't want change anything press: 9!");
				System.out.println("If you don't want change anything else press: 0!");
			}
				
		}
		
		return change;
	}
	
	@Override
	public void enter() {
		System.out.println(this.superscription + " " + this.name_or_brand_name + " " + "entered.");
	}
}
