package technology_store;

import java.util.Scanner;

public class customers extends humans {
	public String name_or_brand_name;
	protected String superscription;
	
	public customers(String name_or_brand_name, String superscription) {
		this.name_or_brand_name = name_or_brand_name;
		this.superscription = superscription;
	}
	public int[] stock = {0,0,0,0,0,0,0};
	double mainmoney = 0.0;
	Scanner scam = new Scanner(System.in);
	
	
	public int[] see(double cost1, int stock1, double cost2, int stock2, double cost3, int stock3, double cost4, int stock4, double cost5, int stock5, double cost6, int stock6) {
		int x = 2;
	
		System.out.println("Which devices do you want to buy? 1/2/3/4/5/6");
		System.out.println("If you don't want to buy anything press: 9!");
		System.out.println("If you buy something and you want finish shopping press: 0!");
		
		while(x>1) {
			
			int numb = scam.nextInt();
			
			if(numb==1) {
				if (stock1 > 0) {
					stock[0]-=1;
					mainmoney+=cost1;
				}
				else {
					System.out.println("We don't have this device!");
				}
				stock1-=1;
			}
		
			else if(numb==2) {
				if (stock2 > 0) {
					stock[1]-=1;
					mainmoney+=cost2;
				}
				else {
					System.out.println("We don't have this device!");
				}
				stock2-=1;
			}
			
			else if(numb==3) {
				if (stock3 > 0) {
					stock[2]-=1;
					mainmoney+=cost3;
				}
				else {
					System.out.println("We don't have this device!");
				}
				stock3-=1;
			}
			
			else if(numb==4) {
				if (stock4 > 0) {
					stock[3]-=1;
					mainmoney+=cost4;
				}
				else {
					System.out.println("We don't have this device!");
				}
				stock4-=1;
			}
			
			else if(numb==5) {
				if (stock5 > 0) {
					stock[4]-=1;
					mainmoney+=cost5;
				}
				else {
					System.out.println("We don't have this device!");
				}
				stock5-=1;
			}
			
			else if(numb==6) {
				if (stock6 > 0) {
					stock[5]-=1;
					mainmoney+=cost6;
				}
				else {
					System.out.println("We don't have this device!");
				}
				stock6-=1;
			}
			
			else if(numb==9) {
				stock[6]=6;
				x=0;
			}
				
			else if(numb==0) {
				System.out.println("Your payment cost: " + mainmoney + " $");
				System.out.println("Seçtikleriniz:");
				x=0;
			}
			
			else {
				System.out.println("Invalid entry!");
				System.out.println("Which devices do you want to buy? 1/2/3/4/5/6");
				System.out.println("If you don't want to buy anything press: 9!");
				System.out.println("If you buy something and you want finish shopping press: 0!");
			}
			
		}
		
		return stock;
	}
	
	public int[] sell(double cost1, double cost2, double cost3, double cost4, double cost5, double cost6) {
		int x = 1;
		
		System.out.println("Which devices do you want to sell? 1/2/3/4/5/6");
		System.out.println("If you don't want to sell anything press: 9!");
		System.out.println("If you buy something and you want finish shopping press: 0!");
		
		while(x==1) {

			int numb = scam.nextInt();
			
			if(numb==1) {
				stock[0]+=1;
				mainmoney+=cost1/2;
			}
		
			else if(numb==2) {
				stock[1]+=1;
				mainmoney+=cost2/2;
			}
			
			else if(numb==3) {
				stock[2]+=1;
				mainmoney+=cost3/2;
			}
			
			else if(numb==4) {
				stock[3]+=1;
				mainmoney+=cost4/2;
			}
			
			else if(numb==5) {
				stock[4]+=1;
				mainmoney+=cost5/2;
			}
			
			else if(numb==6) {
				stock[5]+=1;
				mainmoney+=cost6/2;
			}
			
			else if(numb==9) {
				stock[6]=6;
				x=0;
			}
				
			else if(numb==0) {
				System.out.println("Your alma cost: " + mainmoney + " $");
				System.out.println("Bize sattıklarınız:");
				x=0;
			}
			
			else {
				System.out.println("Invalid entry!");
				System.out.println("Which devices do you want to sell? 1/2/3/4/5/6");
				System.out.println("If you don't want to sell anything press: 9!");
				System.out.println("If you buy something and you want finish shopping press: 0!");
			}
				
		}
		
		return stock;
	}
		
	public int confirm() {
		System.out.print("If you want to buy or sell them press: Y else: N ");
		int x=2;
		while (x==2) {
			String str = scam.next();
			
			if(str.equals("Y") || str.equals("y")) {
				x=1;
			}
				
			else if(str.equals("N") || str.equals("n")) {
				x=0;
			}
			
			else {
				System.out.println("Invalid entry!");
				System.out.print("If you want to buy or sell them press: Y else: N ");
			}
			
		}
		return x;
	}
	
	@Override
	public void enter() {
		System.out.println(this.superscription + " " + this.name_or_brand_name + " entered." );
	}
	
}
